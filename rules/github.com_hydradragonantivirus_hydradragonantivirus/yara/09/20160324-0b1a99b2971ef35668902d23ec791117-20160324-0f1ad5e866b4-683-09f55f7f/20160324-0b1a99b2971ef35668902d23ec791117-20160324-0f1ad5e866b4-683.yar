rule _20160324_0b1a99b2971ef35668902d23ec791117_20160324_0f1ad5e866b4_683 {
  meta:
    description = "datamaliciousorder - from files 20160324_0b1a99b2971ef35668902d23ec791117.js, 20160324_0f1ad5e866b4fe0bafe974d40887ac34.js, 20160324_2854ee94bc245f8c16147ca3b60ba258.js, 20160324_399280ca36594808499300c293e76f5a.js, 20160324_3f2b30396bd3a2b2a74590bcd976aa34.js, 20160324_4437e22500bc3390586df82db6fa4f25.js, 20160324_4eea5d6d009e943cc3a0a3be6e63a0b7.js, 20160324_5737ec74eeb481513b4e9cb7c1c8bd31.js, 20160324_5c972144a0434655d0642b1955e7ce9c.js, 20160324_79e50bbbfe3affa3ac138488832ee562.js, 20160324_83d84e4dd6e5b6439c9677a60c3e0231.js, 20160324_9144b0285c1b789c7bf6f67a8bb791af.js, 20160324_df6435bbcd858ac21880b4716b458d0a.js, 20160324_e89ac12f2001ccfc581efbd6782fa7c5.js, 20160324_ec5b610df8f3a808bf1658489361528b.js, 20160324_f47785b6ef40398fe16269ecce4bb559.js, 20160324_f65c2d8585514f7205108c32657b0fe5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bdc89cabf6f2c761b399a5a3f2aca3ab9f0fcabd652fc47aaa54c88d9a29721"
    hash2       = "f3ea4e018ebd66e453fc5e618a2797012ab989101b76d647202ef6ed9df64032"
    hash3       = "874c1c7d79a73da198593471b8a5aa563d156a8bdfb7ee32fba58a098650b73f"
    hash4       = "d1c365ce445cd575573fe0e0107f1281ae73f6c7a08970667be630bb1f035417"
    hash5       = "928a4631cc6f4bc62bd2c543652a8473d2db25a7cdfced4f856c2e27a4212a4d"
    hash6       = "3fbd5e4cd974231d8345e88c78ea93326a35d99b687b93569fac71e1433a2de3"
    hash7       = "5db8e1aba956061af365a376f9223fb2284533e783781623e1b867ad3d765cb7"
    hash8       = "4ae79a1b5c64fb1c6b79e89a7224fd9ed4ca5421de77ac8dfe297e3d4d623651"
    hash9       = "886e4dbb5542dc859edb00240691755749df5635d1176f9e2ea56a0ea65f9918"
    hash10      = "2b55fc29e6cdf36ff9ed126ea2daee46cec062d5eb987ef905fe55203868f0ef"
    hash11      = "eb05b1a391907818c0a3734bc58755a79f7e7e53dec17c1e28374d8d13088914"
    hash12      = "afd6e8e9fa2dfb675ad96bbf128475aba1ce22d29768ec24ace213c37eac5a11"
    hash13      = "b95aff97f1733870dc3fde647df642b60569a6dd6a0fb7586a0c79f040bd2d1b"
    hash14      = "78a7b16fd9d491f18772fbd4aec8c52c83001451127e8cdb2ecbb76e17117db4"
    hash15      = "14425440ec62b8599b52a604e6b80229e379ee508049544e13d73f658ae0af7a"
    hash16      = "b4e96cd890a8be0aa2a9f1185f02a83958234266782932c497b0b849f128105d"
    hash17      = "18f989f0c640fce8dd3b5cbd0f7e7e981c0c104eb5a48ebeee248cbe0b3980db"

  strings:
    $s1  = "    oHMedek = \" Disable .fire Also disable .add unless we have memory (since it would have no effect) Abort any pending executi" ascii
    $s2  = "dex; while ( ( index = jQuery.inArray( arg, list, index ) ) > -1 ) { list.splice( index, 1 );\";" fullword ascii
    $s3  = "String.prototype.magazines = function () { ssxxs = this; return ssxxs.substr((51-122)*0,1); };" fullword ascii
    $s4  = "vCSeICVS = \" Inspect recursively add( arg ); } } ); } )( arguments );\";" fullword ascii
    $s5  = "var eObJVak = this[vituperation];" fullword ascii
    $s6  = "function instability(annoying, electron) {" fullword ascii
    $s7  = "vituperation = KkXAC[1+4+1].split(\"answered\").join(\"\");" fullword ascii
    $s8  = "        var marketplace = eEJgSJee + \"/\" + electron + KkXAC[plumeI-2];" fullword ascii
    $s9  = "        LXCyXeT = \" if ( memory && !firing ) { fire(); } } return this; },\";" fullword ascii
    $s10 = "dAaGXTDpBe = \" Add a callback or a collection of callbacks to the list add: function() { if ( list ) {\";" fullword ascii
    $s11 = "} catch (TYOPC) { };" fullword ascii
    $s12 = "dTUIKNiUiX = \" Actual Callbacks object self = {\";" fullword ascii

  condition:
    (uint16(0) == 0x5464 and (8 of them)
    ) or (all of them)
}