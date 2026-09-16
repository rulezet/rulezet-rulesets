rule TTP_XOR_QUAD_CurrentVersionRun_c4a3 {
  strings:
    $key_c4a3 = { 97 cc [2] b3 c2 [2] 98 ee [2] b6 cc [2] a2 d7 [2] ad cd [2] b3 d0 [2] b1 d1 [2] aa d7 [2] b6 d0 [2] aa ff }

  condition:
    any of them
}