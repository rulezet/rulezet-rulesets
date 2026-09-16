rule TTP_XOR_QUAD_CurrentVersionRun_fed2 {
  strings:
    $key_fed2 = { ad bd [2] 89 b3 [2] a2 9f [2] 8c bd [2] 98 a6 [2] 97 bc [2] 89 a1 [2] 8b a0 [2] 90 a6 [2] 8c a1 [2] 90 8e }

  condition:
    any of them
}