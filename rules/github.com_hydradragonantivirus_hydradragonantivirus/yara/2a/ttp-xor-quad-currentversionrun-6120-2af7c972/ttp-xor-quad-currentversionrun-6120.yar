rule TTP_XOR_QUAD_CurrentVersionRun_6120 {
  strings:
    $key_6120 = { 32 4f [2] 16 41 [2] 3d 6d [2] 13 4f [2] 07 54 [2] 08 4e [2] 16 53 [2] 14 52 [2] 0f 54 [2] 13 53 [2] 0f 7c }

  condition:
    any of them
}