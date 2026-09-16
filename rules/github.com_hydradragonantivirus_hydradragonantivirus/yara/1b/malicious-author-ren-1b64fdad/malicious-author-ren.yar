rule malicious_author_ren: PDF raw {
  meta:
    author  = "Glenn Edwards (@hiddenillusion)"
    version = "0.1"
    weight  = 5

  strings:
    $magic = "%PDF"

    $reg0 = /Creator.?\(yen vaw\)/
    $reg1 = /Title.?\(who cis\)/
    $reg2 = /Author.?\(ser pes\)/

  condition:
    $magic in (0..1024) and all of ($reg*)
}