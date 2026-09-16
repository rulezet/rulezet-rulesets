rule TTP_XOR_QUAD_CurrentVersionRun_eb9d {
  strings:
    $key_eb9d = { b8 f2 [2] 9c fc [2] b7 d0 [2] 99 f2 [2] 8d e9 [2] 82 f3 [2] 9c ee [2] 9e ef [2] 85 e9 [2] 99 ee [2] 85 c1 }

  condition:
    any of them
}