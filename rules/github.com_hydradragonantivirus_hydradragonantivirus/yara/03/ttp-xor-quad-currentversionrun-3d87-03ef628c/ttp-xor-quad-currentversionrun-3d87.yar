rule TTP_XOR_QUAD_CurrentVersionRun_3d87 {
  strings:
    $key_3d87 = { 6e e8 [2] 4a e6 [2] 61 ca [2] 4f e8 [2] 5b f3 [2] 54 e9 [2] 4a f4 [2] 48 f5 [2] 53 f3 [2] 4f f4 [2] 53 db }

  condition:
    any of them
}