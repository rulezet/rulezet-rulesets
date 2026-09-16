rule TTP_XOR_QUAD_CurrentVersionRun_f829 {
  strings:
    $key_f829 = { ab 46 [2] 8f 48 [2] a4 64 [2] 8a 46 [2] 9e 5d [2] 91 47 [2] 8f 5a [2] 8d 5b [2] 96 5d [2] 8a 5a [2] 96 75 }

  condition:
    any of them
}