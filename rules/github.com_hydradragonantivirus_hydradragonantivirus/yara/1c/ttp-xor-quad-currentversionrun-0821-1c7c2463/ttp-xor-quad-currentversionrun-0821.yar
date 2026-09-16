rule TTP_XOR_QUAD_CurrentVersionRun_0821 {
  strings:
    $key_0821 = { 5b 4e [2] 7f 40 [2] 54 6c [2] 7a 4e [2] 6e 55 [2] 61 4f [2] 7f 52 [2] 7d 53 [2] 66 55 [2] 7a 52 [2] 66 7d }

  condition:
    any of them
}