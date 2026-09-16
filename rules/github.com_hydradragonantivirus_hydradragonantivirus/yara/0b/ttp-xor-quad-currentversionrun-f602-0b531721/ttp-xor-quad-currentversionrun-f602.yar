rule TTP_XOR_QUAD_CurrentVersionRun_f602 {
  strings:
    $key_f602 = { a5 6d [2] 81 63 [2] aa 4f [2] 84 6d [2] 90 76 [2] 9f 6c [2] 81 71 [2] 83 70 [2] 98 76 [2] 84 71 [2] 98 5e }

  condition:
    any of them
}