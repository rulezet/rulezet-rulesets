rule TTP_XOR_QUAD_CurrentVersionRun_3f81 {
  strings:
    $key_3f81 = { 6c ee [2] 48 e0 [2] 63 cc [2] 4d ee [2] 59 f5 [2] 56 ef [2] 48 f2 [2] 4a f3 [2] 51 f5 [2] 4d f2 [2] 51 dd }

  condition:
    any of them
}