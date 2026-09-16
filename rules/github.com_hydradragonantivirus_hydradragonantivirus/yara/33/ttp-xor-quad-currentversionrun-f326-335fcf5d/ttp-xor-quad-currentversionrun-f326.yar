rule TTP_XOR_QUAD_CurrentVersionRun_f326 {
  strings:
    $key_f326 = { a0 49 [2] 84 47 [2] af 6b [2] 81 49 [2] 95 52 [2] 9a 48 [2] 84 55 [2] 86 54 [2] 9d 52 [2] 81 55 [2] 9d 7a }

  condition:
    any of them
}