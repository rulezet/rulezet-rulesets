rule Crypton__32_lil_AND_ {
  strings:
    $a0 = { fc f3 cf 3f [0-20] f3 cf 3f fc [0-20] cf 3f fc f3 [0-20] 3f fc f3 cf [0-20] fc cf fc cf [0-20] 3f f3 3f f3 [0-20] cf fc cf fc [0-20] f3 3f f3 3f [0-20] 01 01 01 01 }

  condition:
    $a0
}