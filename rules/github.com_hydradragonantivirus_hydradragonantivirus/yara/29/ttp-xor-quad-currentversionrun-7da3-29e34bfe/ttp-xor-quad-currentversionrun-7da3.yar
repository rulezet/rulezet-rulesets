rule TTP_XOR_QUAD_CurrentVersionRun_7da3 {
  strings:
    $key_7da3 = { 2e cc [2] 0a c2 [2] 21 ee [2] 0f cc [2] 1b d7 [2] 14 cd [2] 0a d0 [2] 08 d1 [2] 13 d7 [2] 0f d0 [2] 13 ff }

  condition:
    any of them
}