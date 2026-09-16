rule TTP_XOR_QUAD_CurrentVersionRun_0010 {
  strings:
    $key_0010 = { 53 7f [2] 77 71 [2] 5c 5d [2] 72 7f [2] 66 64 [2] 69 7e [2] 77 63 [2] 75 62 [2] 6e 64 [2] 72 63 [2] 6e 4c }

  condition:
    any of them
}