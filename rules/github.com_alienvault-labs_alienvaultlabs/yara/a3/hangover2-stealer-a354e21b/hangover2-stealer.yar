rule Hangover2_stealer {

  strings:

    $a = "MyWebClient" wide ascii

    $b = "Location: {[0-9]+}" wide ascii

    $c = "[%s]:[C-%s]:[A-%s]:[W-%s]:[S-%d]" wide ascii

  condition:

    all of them
}