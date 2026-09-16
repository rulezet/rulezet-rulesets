rule TTP_XOR_QUAD_CurrentVersionRun_1935 {
  strings:
    $key_1935 = { 4a 5a [2] 6e 54 [2] 45 78 [2] 6b 5a [2] 7f 41 [2] 70 5b [2] 6e 46 [2] 6c 47 [2] 77 41 [2] 6b 46 [2] 77 69 }

  condition:
    any of them
}