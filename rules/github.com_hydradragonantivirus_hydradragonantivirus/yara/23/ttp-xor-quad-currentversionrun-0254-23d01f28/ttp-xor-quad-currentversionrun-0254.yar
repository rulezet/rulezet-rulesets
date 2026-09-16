rule TTP_XOR_QUAD_CurrentVersionRun_0254 {
  strings:
    $key_0254 = { 51 3b [2] 75 35 [2] 5e 19 [2] 70 3b [2] 64 20 [2] 6b 3a [2] 75 27 [2] 77 26 [2] 6c 20 [2] 70 27 [2] 6c 08 }

  condition:
    any of them
}