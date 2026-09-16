rule TTP_XOR_QUAD_CurrentVersionRun_3d00 {
  strings:
    $key_3d00 = { 6e 6f [2] 4a 61 [2] 61 4d [2] 4f 6f [2] 5b 74 [2] 54 6e [2] 4a 73 [2] 48 72 [2] 53 74 [2] 4f 73 [2] 53 5c }

  condition:
    any of them
}