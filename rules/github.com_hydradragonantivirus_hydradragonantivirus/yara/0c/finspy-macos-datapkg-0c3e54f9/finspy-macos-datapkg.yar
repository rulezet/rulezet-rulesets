rule finspy_macos_datapkg {
  meta:
    description = "Rule for FinSpy OSX core module"
    author      = "Etienne Maynier, Amnesty Tech"

  strings:
    $s1  = "vlacwjwcefforoxisdryuvbqlxvxt" ascii
    $s2  = "vquyqefxqpwytfuherfvzwaqqyanaddmvquyqefxqpwytfu" ascii
    $s3  = "vsczabsutfuhajffslhlkulomhivwligvscza:" ascii
    $s4  = "ijfrkptshbsurggfqxshpiolwupesxewijfrkptxnj" ascii
    $s5  = "wwsodegezqrtafprejkrytzablizbddgwwsodegezqrtafprejxnj" ascii
    $s6  = "clfggqtyflyspjewoxpodxesnpavcpofclfggqtyflyspjewoxpodxesnpavcpofclfggqtyflyspjewoxpodx" ascii
    $s7  = "mhqxzxdbxsfblsxmidzcribjewzkezujmhqxzxdbxsfblsxmidzcribjewzkezujmh" ascii
    $s8  = "sqpviurrqssxwzrzdwldcanprnsuadyhsqpvixnj" ascii
    $s9  = "zfocytolmylaejykmwphsbchfkfzyadbzfocytolmylaejykmwphsbchfkfzyadbz" ascii
    $s10 = "fehbsdjwmqrdndkskegllpixxabegjrdfehbsdjwmqrdndkske" ascii
    $s11 = "exmycityouezjfdczebdfhqdgt:" ascii
    $s12 = "denueozlbzhqzzdjhxjnjhoadjdsmashdenueozlbzhqzzd" ascii

  condition:
    uint16(0) == 0xFACF and 8 of them
}