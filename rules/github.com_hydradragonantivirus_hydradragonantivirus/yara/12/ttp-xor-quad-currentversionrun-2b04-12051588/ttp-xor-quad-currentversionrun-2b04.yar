rule TTP_XOR_QUAD_CurrentVersionRun_2b04 {
  strings:
    $key_2b04 = { 78 6b [2] 5c 65 [2] 77 49 [2] 59 6b [2] 4d 70 [2] 42 6a [2] 5c 77 [2] 5e 76 [2] 45 70 [2] 59 77 [2] 45 58 }

  condition:
    any of them
}