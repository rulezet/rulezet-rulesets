rule Crypton__32_big_AND_ {
  strings:
    $a0 = { 3f cf f3 fc [0-20] fc 3f cf f3 [0-20] f3 fc 3f cf [0-20] cf f3 fc 3f [0-20] cf fc cf fc [0-20] f3 3f f3 3f [0-20] fc cf fc cf [0-20] 3f f3 3f f3 [0-20] 01 01 01 01 }

  condition:
    $a0
}