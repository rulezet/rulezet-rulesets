rule tibetan_indecent_infrastructure_strings {
  meta:
    author = "Matt Brooks, @cmatthewbrooks"

  strings:
    $cc1  = "103.55.24.196" ascii wide nocase
    $cc2  = "118.99.59.105" ascii wide nocase
    $cc3  = "27.126.186.222" ascii wide nocase
    $cc4  = "45.127.97.222" ascii wide nocase
    $cc5  = "comemail.email" ascii wide nocase
    $cc6  = "commail.co" ascii wide nocase
    $cc7  = "daynew.today" ascii wide nocase
    $cc8  = "daynews.today" ascii wide nocase
    $cc9  = "tibetfrum.info" ascii wide nocase
    $cc10 = "tibethouse.info" ascii wide nocase
    $cc11 = "tibetnews.info" ascii wide nocase
    $cc12 = "tibetnews.today" ascii wide nocase

  condition:
    any of them

}