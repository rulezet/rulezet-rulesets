rule TTP_XOR_QUAD_CurrentVersionRun_b8ac {
  strings:
    $key_b8ac = { eb c3 [2] cf cd [2] e4 e1 [2] ca c3 [2] de d8 [2] d1 c2 [2] cf df [2] cd de [2] d6 d8 [2] ca df [2] d6 f0 }

  condition:
    any of them
}