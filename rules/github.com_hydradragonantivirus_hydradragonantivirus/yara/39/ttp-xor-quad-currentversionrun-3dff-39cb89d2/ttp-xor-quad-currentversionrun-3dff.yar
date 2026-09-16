rule TTP_XOR_QUAD_CurrentVersionRun_3dff {
  strings:
    $key_3dff = { 6e 90 [2] 4a 9e [2] 61 b2 [2] 4f 90 [2] 5b 8b [2] 54 91 [2] 4a 8c [2] 48 8d [2] 53 8b [2] 4f 8c [2] 53 a3 }

  condition:
    any of them
}