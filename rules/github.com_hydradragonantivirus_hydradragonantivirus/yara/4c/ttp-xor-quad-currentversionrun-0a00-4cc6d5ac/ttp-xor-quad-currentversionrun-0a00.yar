rule TTP_XOR_QUAD_CurrentVersionRun_0a00 {
  strings:
    $key_0a00 = { 59 6f [2] 7d 61 [2] 56 4d [2] 78 6f [2] 6c 74 [2] 63 6e [2] 7d 73 [2] 7f 72 [2] 64 74 [2] 78 73 [2] 64 5c }

  condition:
    any of them
}