rule webshell_wp_menus {
  meta:
    description = "PHP - file webshell_wp-menus.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "51ba6bcf991fc31bca914797a90aec63b11ac506f0d76dd632c016b814c3ab9b"

  strings:
    $s1 = "<?php function absfsfrsxvcxvx($a,$b,$c,$d,$e){return $a.$b.$c.$d.$e;}$tRHzWnG3890 = \"r7vmb.l2tup96;ke3zd0sjn*xg4(5o_fc1hyi/awq8" ascii
    $s2 = "u7028uEyJGxuYOnFGXr/7xzyI3agbzqcIxfN3YEy9KXTMh9PjLjT/9PD4CHrDbtYeUlP+/a/hfMpnA0BEcejNIt+Jxm5ULtGoqb4J3XgeTpkXdfloyuynfHSBhhnVouP" ascii
    $s3 = "oXFc4qPWHtf5E3HvQGEyeeNKmbMdDS6es2T8wiOdnB+uPMUSNZg0GJ2aJWTW9e8h1ck2EitS7LWUZptTS2mN1a632U39wEd0vf/4/W1/uV0prVtXcHMQ79Xvf5Oa0Izw" ascii
    $s4 = "CtIZtK7zy+m4CD7PACeME+hwgAH8fDthYg8JjPIWyH0xgz3VDDerKcxcIBZ26e/KOneHa4LlOOAOqRN7hO7ZHbZuHDlLPQbwZbzDbcHzfAsCKts6zAwd0iKFT3edHbN0" ascii
    $s5 = "U5n3F3SNlOmw5HZldTKOJ+P9Mswy7Iz1HRvc0vTIvO1qNF4kODCOM6j7Z3zE9UCS/AG6JdwpwNmB45BraepbXG+l3iUU+nax//4uM8mCT7oWwPovDZhqxCu1oaKc8ASo" ascii
    $s6 = "GhswMwoqj/36qqi/TPReEnOznec96vXdspru6uvpeXVVdVXLm8bg7c6KItZk1eDIc9J1mv1ff/PnJ8GFjMHzQdx4+Gjz42XnSGNYfWlv//lepH/hBiNA/DIY8ZeAOnbk" ascii
    $s7 = "JGp2NgXu1gZOLHEqzHzOcduS77qzcMDXlJhOIlSaeA61ZxJz5V/YXG4XujHFaKbAs8oFWxj6NXMnp7apsLe+Rfl6P9EWPGMzcbZ3Sz+0Uy4hY/D/US/079FLf7KXv4ol" ascii
    $s8 = "Tvc2mTO7jMz5K3j3dOzxkccBe7n/kuckc4xCQgfkEyCGSRWFAPN/fU/kDfKCnZz47PEoK4/LnuVDGqJwPt5mpivINQQ7U4ZFRUqx+I1NRxBe7yFQuqRndOBlaDYleVNf" ascii
    $s9 = "SMZOHvQ+YYpfeuqJOqwj/wPXdWLVWjRxPfo4VkeZHPqJVKiPpfJa+q+uNSruN/k3ZU64YatHf6sUVPQwxNWPqiRj+EXoxxi+qKVUY058fKkLuSVBek7y28jycYKyMklp" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 70KB and
      (all of them)
    ) or (all of them)
}