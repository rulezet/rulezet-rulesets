rule TTP_XOR_QUAD_CurrentVersionRun_0534 {
  strings:
    $key_0534 = { 56 5b [2] 72 55 [2] 59 79 [2] 77 5b [2] 63 40 [2] 6c 5a [2] 72 47 [2] 70 46 [2] 6b 40 [2] 77 47 [2] 6b 68 }

  condition:
    any of them
}