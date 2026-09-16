rule Tranx_not_receive_Ref_Ba0920019_pdf {
  meta:
    description = "datamaliciousorder - file Tranx_not_receive_Ref_Ba0920019_pdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b8d52fd0dc9b98235b8558bcf9312ac7aafcac32f100727671cc0f1be325911"

  strings:
    $s1  = "var _0x28188,_0x2671C,_0x27FCB,_0x264AD,_0x27DB5,_0x27131,_0x27BF8,_0x27C51,_0x2655F,_0x27B9F,_0x265B8,_0x26932,_0x2666A,_0x273F" ascii
    $s2  = "){function _0x3275D(_0x262F0){return -_0x262F0}function _0x31A27(){return _0x269E4}function _0x31811(){return _0x263A2}function " ascii
    $s3  = "x26349){return _0x262F0* _0x26349}function _0x31549(_0x262F0,_0x26349){return _0x262F0- _0x26349}function _0x31706(){return _0x2" ascii
    $s4  = "n _0x3143E(_0x262F0,_0x26349){return _0x262F0% _0x26349}function _0x314F0(_0x262F0,_0x26349){return _0x262F0+ _0x26349}function " ascii
    $s5  = "ot1%p#g%db#u#_#vru#l1hif%#111\",2201828);if(!_0x28502){_0x2855B();(function(){_0x285B4= _0x28502[5]})()};function _0x285B4(_0x26" ascii
    $s6  = "0x31AD9(){return _0x26A96}function _0x31B32(){return _0x26AEF}function _0x32547(){return _0x283F7}function _0x31C3D(){return _0x" ascii
    $s7  = "13(){_0x285B4= true}function _0x3BAC5(){_0x285B4= _0x28502[3]}function _0x30FB9(){return  function(_0x26349){var _0x262F0={};_0x" ascii
    $s8  = "on _0x34F58(_0x262F0,_0x26349){_0x262F0._[_0x28502[1]]= _0x26349._[_0x28502[1]]}function _0x34FB1(_0x262F0,_0x26349){_0x262F0._[" ascii
    $s9  = "83]}function _0x3BBD0(_0x262F0){_0x262F0._= 1}function _0x328C1(){_0x285B4= false}function _0x3291A(){_0x2855B= 1}function _0x32" ascii
    $s10 = "64AD;_0x26349._= _0x26454;if(_0x315FB(_0x2855B,null)){_0x31706()()};return _0x300C6(_0x262F0,_0x263A2,_0x26349)}}function _0x301" ascii
    $s11 = ",false)){return}else {(1&&_0x29A37._)()};return}};(1&&_0x29CFF._)(_0x2C396._);if(_0x315FB(_0x2855B,0)){_0x316AD()(_0x28502[5]);_" ascii
    $s12 = "eturn};return};if((1&&_0x296BD._)(_0x26349._)){(1&&_0x2807D._)()();return};(1&&_0x2A39A._)(_0x2C33D);if(_0x315FB(_0x285B4,_0x285" ascii
    $s13 = "63FB;_0x263A2._= _0x264AD;_0x26349._= _0x26454;if(_0x32704(_0x285B4)){return};_0x37648(_0x262F0,_0x263A2,_0x26349)}}function _0x" ascii
    $s14 = "urn  function(){if(_0x31654(_0x285B4,_0x28502[9])){_0x32F03();return};return _0x326AB()}}function _0x29238(){return  function(){" ascii
    $s15 = "48()}}function _0x28A92(){return  function(){return _0x32495()}}function _0x28AEB(){return  function(){return _0x31E53()}}functi" ascii
    $s16 = "}}function _0x2C9D8(_0x262F0,_0x26349,_0x263A2,_0x263FB){return  function(_0x264AD){var _0x26454={};_0x26454._= _0x264AD;return " ascii
    $s17 = "5B4)){_0x31706()(_0x28502[3],false,false)}else {(1&&_0x29186._)()};return};if((1&&_0x296BD._)(_0x263A2._)){(1&&_0x27F19._)()(tru" ascii
    $s18 = "ion(){return (1&&_0x262F0._)()}}function _0x2AB40(_0x262F0){return  function(){_0x38646();return (1&&_0x262F0._)()}}function _0x" ascii
    $s19 = "x262F0){_0x262F0[_0x28502[1]]= true}}function _0x30F07(){return  function(_0x262F0){_0x262F0[_0x28502[1]]= null}}function _0x3BA" ascii
    $s20 = "36860(){_0x2855B= 0}function _0x368B9(){_0x285B4= null}function _0x36912(){_0x2855B= 0}function _0x3696B(){_0x285B4= 0}function " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}