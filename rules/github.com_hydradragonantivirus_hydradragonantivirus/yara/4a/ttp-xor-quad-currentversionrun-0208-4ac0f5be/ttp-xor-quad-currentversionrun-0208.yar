rule TTP_XOR_QUAD_CurrentVersionRun_0208 {
  strings:
    $key_0208 = { 51 67 [2] 75 69 [2] 5e 45 [2] 70 67 [2] 64 7c [2] 6b 66 [2] 75 7b [2] 77 7a [2] 6c 7c [2] 70 7b [2] 6c 54 }

  condition:
    any of them
}