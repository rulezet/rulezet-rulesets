rule Hangover2_backdoor_shell {

  strings:

    $a = "Shell started at: " wide ascii

    $b = "Shell closed at: " wide ascii

    $c = "Shell is already closed!" wide ascii

    $d = "Shell is not Running!" wide ascii

  condition:

    all of them
}