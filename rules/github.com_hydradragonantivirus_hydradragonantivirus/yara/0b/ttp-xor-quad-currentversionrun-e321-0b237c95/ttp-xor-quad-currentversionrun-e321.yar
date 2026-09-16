rule TTP_XOR_QUAD_CurrentVersionRun_e321 {
  strings:
    $key_e321 = { b0 4e [2] 94 40 [2] bf 6c [2] 91 4e [2] 85 55 [2] 8a 4f [2] 94 52 [2] 96 53 [2] 8d 55 [2] 91 52 [2] 8d 7d }

  condition:
    any of them
}