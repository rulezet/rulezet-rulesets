rule TTP_XOR_QUAD_CurrentVersionRun_3d0d {
  strings:
    $key_3d0d = { 6e 62 [2] 4a 6c [2] 61 40 [2] 4f 62 [2] 5b 79 [2] 54 63 [2] 4a 7e [2] 48 7f [2] 53 79 [2] 4f 7e [2] 53 51 }

  condition:
    any of them
}