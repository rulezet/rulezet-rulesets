rule TTP_XOR_QUAD_CurrentVersionRun_3029 {
  strings:
    $key_3029 = { 63 46 [2] 47 48 [2] 6c 64 [2] 42 46 [2] 56 5d [2] 59 47 [2] 47 5a [2] 45 5b [2] 5e 5d [2] 42 5a [2] 5e 75 }

  condition:
    any of them
}