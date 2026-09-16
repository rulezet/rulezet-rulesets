rule TTP_XOR_QUAD_CurrentVersionRun_f221 {
  strings:
    $key_f221 = { a1 4e [2] 85 40 [2] ae 6c [2] 80 4e [2] 94 55 [2] 9b 4f [2] 85 52 [2] 87 53 [2] 9c 55 [2] 80 52 [2] 9c 7d }

  condition:
    any of them
}