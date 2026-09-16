rule TTP_XOR_QUAD_CurrentVersionRun_7935 {
  strings:
    $key_7935 = { 2a 5a [2] 0e 54 [2] 25 78 [2] 0b 5a [2] 1f 41 [2] 10 5b [2] 0e 46 [2] 0c 47 [2] 17 41 [2] 0b 46 [2] 17 69 }

  condition:
    any of them
}