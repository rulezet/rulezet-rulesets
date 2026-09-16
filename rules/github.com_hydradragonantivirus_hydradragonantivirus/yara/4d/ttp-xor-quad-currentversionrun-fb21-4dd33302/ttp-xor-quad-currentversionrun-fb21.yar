rule TTP_XOR_QUAD_CurrentVersionRun_fb21 {
  strings:
    $key_fb21 = { a8 4e [2] 8c 40 [2] a7 6c [2] 89 4e [2] 9d 55 [2] 92 4f [2] 8c 52 [2] 8e 53 [2] 95 55 [2] 89 52 [2] 95 7d }

  condition:
    any of them
}