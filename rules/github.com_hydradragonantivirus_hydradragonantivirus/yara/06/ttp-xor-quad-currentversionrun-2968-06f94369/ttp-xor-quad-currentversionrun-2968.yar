rule TTP_XOR_QUAD_CurrentVersionRun_2968 {
  strings:
    $key_2968 = { 7a 07 [2] 5e 09 [2] 75 25 [2] 5b 07 [2] 4f 1c [2] 40 06 [2] 5e 1b [2] 5c 1a [2] 47 1c [2] 5b 1b [2] 47 34 }

  condition:
    any of them
}