rule TTP_XOR_QUAD_CurrentVersionRun_f698 {
  strings:
    $key_f698 = { a5 f7 [2] 81 f9 [2] aa d5 [2] 84 f7 [2] 90 ec [2] 9f f6 [2] 81 eb [2] 83 ea [2] 98 ec [2] 84 eb [2] 98 c4 }

  condition:
    any of them
}