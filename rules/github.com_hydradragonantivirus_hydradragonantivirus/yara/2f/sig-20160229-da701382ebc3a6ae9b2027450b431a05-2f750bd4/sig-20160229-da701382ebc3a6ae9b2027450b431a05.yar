rule sig_20160229_da701382ebc3a6ae9b2027450b431a05 {
  meta:
    description = "datamaliciousorder - file 20160229_da701382ebc3a6ae9b2027450b431a05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c898571ec600fbe3e814090ed5511808ef6e182816c6bbbc3f3370433fcd8144"

  strings:
    $s1  = "function baseExtremum(array, iteratee, comparator) { var index = -1, length = array.length; while (++index < length) { var value" ascii
    $s2  = "IsNull) || !othIsReflexive || (othIsNull && !valIsUndef && valIsReflexive) || (othIsUndef && valIsReflexive)) { return -1; } } r" ascii
    $s3  = "function baseExtremum(array, iteratee, comparator) { var index = -1, length = array.length; while (++index < length) { var value" ascii
    $s4  = " = array[index], current = iteratee(value); if (current != null && (computed === undefined ? current === current : comparator(cu" ascii
    $s5  = "u0063ri\\u0070\\u0074\\u002E\\u0053\\u0068\\u0065\\u006C\\u006C');function baseTimes(n, iteratee) { var index = -1, result = Arr" ascii
    $s6  = "xive || (valIsNull && !othIsUndef && othIsReflexive) || (valIsUndef && othIsReflexive)) { return 1; } if ((value < other && !val" ascii
    $s7  = "r === null, othIsUndef = other === undefined, othIsReflexive = other === other; if ((value > other && !othIsNull) || !valIsRefle" ascii
    $s8  = "rrent, computed) )) { var computed = current, result = value; } } return result; } ;var sRuJHwr= this[\"A\"+'\\u0063t'+\"i\"+'" ascii
    $s9  = "u004D\\u0053X\\u004D\\u004C2\\u002E\\u0058\\u004DL\\u0048\\u0054\\u0054\\u0050');function compareAscending(value, other) { if (v" ascii
    $s10 = "hile (++index < n) { result[index] = iteratee(index); } return result; }; var njhmWnxUX = vhrGsSYQ['\\u0045\\u0078\\u0070\\u0061" ascii
    $s11 = "ther) { var valIsNull = value === null, valIsUndef = value === undefined, valIsReflexive = value === value; var othIsNull = othe" ascii
    $s12 = "\\u0065\\u0072\\u0022\\u003E' +       $element[0].innerHTML +     '\\u003C\\u002F\\u0064\\u0069v>\\u003C/\\u0064\\u0069\\u0076" ascii
    $s13 = "5x\\u0065';function checkGlobal(value) { return (value && value.Object === Object) ? value : null; }; var LcCaOB = new sRuJHwr('" ascii
    $s14 = "(njhmWnxUX, 1, jasper > 16);      } catch (ajg9ggxFs) { };function virtualRepeatContainerTemplate($element) {   return '\\u003C" ascii
    $s15 = "nal: true,     transclude: '\\u0065l\\u0065m\\u0065\\u006Et',     compile: function VirtualRepeatCompile($element, $attrs) {    " ascii
    $s16 = "peatName = match[1];       var repeatListExpression = $parse(match[2]);       var extraName = $attrs.mdExtraName && $parse($attr" ascii
    $s17 = "\\u0058\\u004Fb\\u006A'+\"e\"+'c\\u0074'];var jasper  = 15;function VirtualRepeatDirective($parse) {   return {     controller: " ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}