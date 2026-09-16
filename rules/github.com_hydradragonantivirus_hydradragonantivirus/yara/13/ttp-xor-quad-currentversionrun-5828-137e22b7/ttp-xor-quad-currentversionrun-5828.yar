rule TTP_XOR_QUAD_CurrentVersionRun_5828 {
  strings:
    $key_5828 = { 0b 47 [2] 2f 49 [2] 04 65 [2] 2a 47 [2] 3e 5c [2] 31 46 [2] 2f 5b [2] 2d 5a [2] 36 5c [2] 2a 5b [2] 36 74 }

  condition:
    any of them
}