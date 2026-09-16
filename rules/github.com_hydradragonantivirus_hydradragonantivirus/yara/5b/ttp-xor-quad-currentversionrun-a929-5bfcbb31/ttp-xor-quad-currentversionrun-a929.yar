rule TTP_XOR_QUAD_CurrentVersionRun_a929 {
  strings:
    $key_a929 = { fa 46 [2] de 48 [2] f5 64 [2] db 46 [2] cf 5d [2] c0 47 [2] de 5a [2] dc 5b [2] c7 5d [2] db 5a [2] c7 75 }

  condition:
    any of them
}