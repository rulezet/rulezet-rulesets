rule TTP_XOR_QUAD_CurrentVersionRun_2e08 {
  strings:
    $key_2e08 = { 7d 67 [2] 59 69 [2] 72 45 [2] 5c 67 [2] 48 7c [2] 47 66 [2] 59 7b [2] 5b 7a [2] 40 7c [2] 5c 7b [2] 40 54 }

  condition:
    any of them
}