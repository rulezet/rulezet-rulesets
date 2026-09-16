rule TTP_XOR_QUAD_CurrentVersionRun_e6a3 {
  strings:
    $key_e6a3 = { b5 cc [2] 91 c2 [2] ba ee [2] 94 cc [2] 80 d7 [2] 8f cd [2] 91 d0 [2] 93 d1 [2] 88 d7 [2] 94 d0 [2] 88 ff }

  condition:
    any of them
}