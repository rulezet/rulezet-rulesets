rule TTP_XOR_QUAD_CurrentVersionRun_0d21 {
  strings:
    $key_0d21 = { 5e 4e [2] 7a 40 [2] 51 6c [2] 7f 4e [2] 6b 55 [2] 64 4f [2] 7a 52 [2] 78 53 [2] 63 55 [2] 7f 52 [2] 63 7d }

  condition:
    any of them
}