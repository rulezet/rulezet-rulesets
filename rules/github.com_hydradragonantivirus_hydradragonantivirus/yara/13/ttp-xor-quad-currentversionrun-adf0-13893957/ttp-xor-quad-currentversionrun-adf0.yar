rule TTP_XOR_QUAD_CurrentVersionRun_adf0 {
  strings:
    $key_adf0 = { fe 9f [2] da 91 [2] f1 bd [2] df 9f [2] cb 84 [2] c4 9e [2] da 83 [2] d8 82 [2] c3 84 [2] df 83 [2] c3 ac }

  condition:
    any of them
}