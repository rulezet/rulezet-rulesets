rule TTP_XOR_QUAD_CurrentVersionRun_3529 {
  strings:
    $key_3529 = { 66 46 [2] 42 48 [2] 69 64 [2] 47 46 [2] 53 5d [2] 5c 47 [2] 42 5a [2] 40 5b [2] 5b 5d [2] 47 5a [2] 5b 75 }

  condition:
    any of them
}