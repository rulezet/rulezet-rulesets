rule _20160419_09658a5c8309d42e32e9074284b8f84b_20160419_207141854b7e_709 {
  meta:
    description = "datamaliciousorder - from files 20160419_09658a5c8309d42e32e9074284b8f84b.js, 20160419_207141854b7ec17a40e920beb871f8cf.js, 20160419_358ac98aa5fc76a60acac3b0ec30c1e4.js, 20160419_3b5871f88d4743890f50f32f43329dbb.js, 20160419_43177ca34c1a0ecf32ea6cfc752391b4.js, 20160419_44ed7d5accbe43320632a781e71051e3.js, 20160419_4f41495bb38077c9d5fc12008710317c.js, 20160419_730dc22110fd8248b3c235802517a936.js, 20160419_7ff482f74b79967aafb044914728307b.js, 20160419_80eaa5dd37486eca51b4da77b5279402.js, 20160419_92340ccea9e6f4d39a09743657ee1ad0.js, 20160419_93c9562da6d609d4c7b38c50e963598d.js, 20160419_985a6b57bab7cb6551f9b85e248f11bb.js, 20160419_ba398c3e273b2a27cdf1abf5b0709e92.js, 20160419_bde8db31f2ccf81371cb21b7dd536c46.js, 20160419_c019a79a58b28aa05de759c9e9994cb4.js, 20160419_c197aac75e254bec21e8cc770cc1f081.js, 20160419_c38e790adeb08351473f660efaf01987.js, 20160419_e349f100fbe66c196472088eb89a8dfa.js, 20160419_e5b6aff1ba56dccebab5ea025bbe8055.js, 20160419_ef6199cb3c7091c0a813c687c7173a3f.js, 20160419_f9150e654a4ddd0f40a16ebdce5d4edd.js, 20160419_fde53d510d11d407188d5d54bb255f46.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32e66ac442d068111a9ba8a7065a51f13bc99d68a0410a6e870a2d2ac4b79cb9"
    hash2       = "d6b6db16b875de660ad80cdc54cd9f67c16782175b07ec29c2642bccdc3dd685"
    hash3       = "1c326d4705bf7d49de303eba494d042f421d780df0778e27c62d34ccb600786e"
    hash4       = "1fe9b18bc32e55e62e548e139ed107b1c2889efa545d19f525d3c4fc3c197549"
    hash5       = "fea420e794518bd3cfd6508b483866f7f82725bc07d686c3401f318c09fa0054"
    hash6       = "b43824eb07816fbf496522205169ace0bbe91e9349379579357b6efe3d7a50fb"
    hash7       = "d60fa9a5e9c91dee9561310a344d1d8126409d88dadec92cef3dfabfd0a173c2"
    hash8       = "09cfe6aa901c7a88c15c5cbdda9a2d8c2d0898bc96075d988ac8c71c1829af5a"
    hash9       = "17faa01a5307a2e43666bb1104215cdcf1738d38cad23be0af17f9c9ac5f45ed"
    hash10      = "5963c625eba857b3ec84d06944aea1c1ee335442ef520cfd7677f6087e3cc46d"
    hash11      = "c92e9150291862458f4ad69f003315d06a847161cf983bab2ade42f749e10938"
    hash12      = "38237cbb932b11b72c186cbc8fab2a3e051df2c5b2ed1ae6979c64651cbff882"
    hash13      = "8192b19550e66572adedb49f7a34c9f37f7e21942bbd2a75b727f45af4a325a9"
    hash14      = "f82b434961172bdf6d38d946c79d4068ab232bfc5e732c19290fffb36c85c274"
    hash15      = "c91fb1e77dbe42499f3a72707fe3daf418c5d911f058cf2e377e146c31bc1f72"
    hash16      = "f3051c0843e4986be48c4ee6a909f7287110eb874278a4f01553aed29afab731"
    hash17      = "2d09680031791a7a8795065b937a2d1666fdf3c0f267282a85282f4fd54d34fb"
    hash18      = "65d299f698541b5d2c70694210fc4b3390b894c0d9381128c6a74675560145e3"
    hash19      = "98a47d9ed4bfc616517bcef22ffb8afb767acc80ef5189d59fc2f1f35a93ec5c"
    hash20      = "5f80a03b43313ee1e8ec22650e6c568b1fe018caf60b0fce792d10d788f95f10"
    hash21      = "45b389392f80c96552d631e602fbd08e6f6829b71ca4ed7b68d057cfa82e0978"
    hash22      = "18a2d82402f651c00c5bf0915f12358e76133b8e084394aea0fa48873f49652b"
    hash23      = "a2451e216a61192f07f417e7b5649c9fa802b595ad3b7cdae87af51387706d15"

  strings:
    $s1  = "    AqqiwAoypAm = \" #11217 - WebKit loses check when the name is after the checked attribute fragment.appendChild( div );\";" fullword ascii
    $s2  = "        RLgFRSU = \" Make sure that link elements get serialized correctly by innerHTML This requires a wrapper element in IE su" ascii
    $s3  = " input.type = \\\"checkbox\\\"; input.checked = true; fragment.appendChild( input ); support.appendChecked = input.checked;\";" fullword ascii
    $s4  = "        RLgFRSU = \" Make sure that link elements get serialized correctly by innerHTML This requires a wrapper element in IE su" ascii
    $s5  = "bWwIlPq = \"function createSafeFragment( document ) { var list = nodeNames.split( \\\"|\\\" ), safeFrag = document.createDocumen" ascii
    $s6  = "bWwIlPq = \"function createSafeFragment( document ) { var list = nodeNames.split( \\\"|\\\" ), safeFrag = document.createDocumen" ascii
    $s7  = "        PvVKiw = \" Make sure that tbody elements aren\\\"t automatically inserted IE will insert them into empty tables support" ascii
    $s8  = "        vwfUqxPgROU = \" if ( safeFrag.createElement ) { while ( list.length ) { safeFrag.createElement( list.pop() ); } } retur" ascii
    $s9  = "   cvqiFiqxJ = \" Support: Windows Web Apps (WWA) `name` and `type` must use .setAttribute for WWA (#14901) input = document.cre" ascii
    $s10 = "        qOlbRvvl = \" IE strips leading whitespace when .innerHTML is used support.leadingWhitespace = div.firstChild.nodeType =" ascii
    $s11 = "        dtuDDuUSDTt = \" Check if a disconnected checkbox will retain its checked value of true after appended to the DOM (IE6/7" ascii
    $s12 = "   cvqiFiqxJ = \" Support: Windows Web Apps (WWA) `name` and `type` must use .setAttribute for WWA (#14901) input = document.cre" ascii
    $s13 = "        vwfUqxPgROU = \" if ( safeFrag.createElement ) { while ( list.length ) { safeFrag.createElement( list.pop() ); } } retur" ascii
    $s14 = "        qOlbRvvl = \" IE strips leading whitespace when .innerHTML is used support.leadingWhitespace = div.firstChild.nodeType =" ascii

  condition:
    (uint16(0) == 0x0a0d and (8 of them)
    ) or (all of them)
}