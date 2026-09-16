rule TTP_XOR_QUAD_CurrentVersionRun_f6a3 {
  strings:
    $key_f6a3 = { a5 cc [2] 81 c2 [2] aa ee [2] 84 cc [2] 90 d7 [2] 9f cd [2] 81 d0 [2] 83 d1 [2] 98 d7 [2] 84 d0 [2] 98 ff }

  condition:
    any of them
}