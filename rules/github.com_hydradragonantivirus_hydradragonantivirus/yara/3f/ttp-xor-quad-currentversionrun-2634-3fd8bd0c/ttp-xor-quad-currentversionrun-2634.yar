rule TTP_XOR_QUAD_CurrentVersionRun_2634 {
  strings:
    $key_2634 = { 75 5b [2] 51 55 [2] 7a 79 [2] 54 5b [2] 40 40 [2] 4f 5a [2] 51 47 [2] 53 46 [2] 48 40 [2] 54 47 [2] 48 68 }

  condition:
    any of them
}