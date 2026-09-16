rule TTP_XOR_QUAD_CurrentVersionRun_ed80 {
  strings:
    $key_ed80 = { be ef [2] 9a e1 [2] b1 cd [2] 9f ef [2] 8b f4 [2] 84 ee [2] 9a f3 [2] 98 f2 [2] 83 f4 [2] 9f f3 [2] 83 dc }

  condition:
    any of them
}