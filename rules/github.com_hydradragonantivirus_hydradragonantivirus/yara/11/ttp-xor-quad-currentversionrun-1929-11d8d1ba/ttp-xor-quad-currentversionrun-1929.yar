rule TTP_XOR_QUAD_CurrentVersionRun_1929 {
  strings:
    $key_1929 = { 4a 46 [2] 6e 48 [2] 45 64 [2] 6b 46 [2] 7f 5d [2] 70 47 [2] 6e 5a [2] 6c 5b [2] 77 5d [2] 6b 5a [2] 77 75 }

  condition:
    any of them
}