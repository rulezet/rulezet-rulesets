rule TTP_XOR_QUAD_CurrentVersionRun_0578 {
  strings:
    $key_0578 = { 56 17 [2] 72 19 [2] 59 35 [2] 77 17 [2] 63 0c [2] 6c 16 [2] 72 0b [2] 70 0a [2] 6b 0c [2] 77 0b [2] 6b 24 }

  condition:
    any of them
}